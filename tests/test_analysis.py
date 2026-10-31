import hashlib
import math
import pytest
from analysis_service import (flip_bit, bit_distance, confusion_diffusion, aes_length_analysis,
                              hashing_resistance_analysis, digest_prefix, _search)
from crypto_service import OperationError


def test_exactly_one_bit_changes():
    for value in (bytes(16), bytes(range(32))):
        for bit in range(len(value)*8):
            assert bit_distance(value, flip_bit(value, bit)) == 1
    with pytest.raises(ValueError):
        flip_bit(b'x', 8)


def test_confusion_diffusion_measurements():
    result = confusion_diffusion(bytes(range(16)), 8)
    assert result.seconds >= 0
    assert len(result.value['rows']) == 16
    for row in result.value['rows']:
        assert 0 <= row['changed_output_bits'] <= 128
        assert row['changed_percent'] == row['changed_output_bits']/128*100
        assert row['encryption_ms'] >= 0
    for kind,mask in result.value['first_trial_masks'].items():
        assert len(mask) == 128 and set(mask) <= {0,1}
        first = next(row for row in result.value['rows'] if row['experiment'] == kind)
        assert sum(mask) == first['changed_output_bits']
    assert result.value['rows'][7]['flipped_bit'] == 127
    assert result.value['rows'][-1]['flipped_bit'] == 255
    for row, trial in zip(result.value['rows'], result.value['trials']):
        baseline = bytes.fromhex(result.value['baseline_hex'])
        output = bytes.fromhex(trial['output_hex'])
        assert bit_distance(baseline, output) == row['changed_output_bits']
        assert trial['changed_bytes'] == sum(a != b for a,b in zip(baseline, output))
        assert row['changed_hex_characters'] == sum(a != b for a,b in zip(baseline.hex(), output.hex()))
        assert row['changed_hex_percent'] == row['changed_hex_characters']/32*100
        assert trial['flipped_bit'] == row['flipped_bit']
    assert 'key' not in result.value


def test_all_aes_key_sizes_and_actual_timings():
    result = aes_length_analysis([16,1024], repeats=2)
    assert result.seconds >= 0
    assert len(result.value['rows']) == 6
    assert {r['key_bits'] for r in result.value['rows']} == {128,192,256}
    for row in result.value['rows']:
        for value in row.values():
            assert math.isfinite(value) and value >= 0
        assert row['repeats'] == 2


def test_password_character_lengths_use_fixed_aes256_and_real_timings():
    from analysis_service import password_length_analysis
    result = password_length_analysis([12,64],size=128,repeats=1)
    assert result.seconds >= 0
    assert [row['password_characters'] for row in result.value['rows']] == [12,64]
    for row in result.value['rows']:
        assert row['key_bits'] == 256 and row['size_bytes'] == 128
        assert row['encrypt_ms'] >= row['aes_encrypt_ms'] >= 0
        assert row['decrypt_ms'] >= row['aes_decrypt_ms'] >= 0
        assert row['encrypt_kdf_ms'] >= 0 and row['decrypt_kdf_ms'] >= 0
        assert 'password' not in row and 'key' not in row
    with pytest.raises(OperationError):
        password_length_analysis([8])


def test_bounded_full_hash_and_prefix_trials():
    result = hashing_resistance_analysis(b'original', attempts=300, repeats=2)
    assert result.seconds >= 0
    assert len(result.value['full']) == 3 and len(result.value['toy']) == 9
    for experiment in result.value['full']:
        assert 1 <= experiment['attempts'] <= 300
        assert experiment['seconds'] >= experiment['hash_seconds'] >= 0
        trace = experiment['progress']
        assert trace[-1]['attempts'] == experiment['attempts']
        assert trace[-1]['matches'] == int(experiment['found'])
        assert all(a['attempts'] <= b['attempts'] for a,b in zip(trace,trace[1:]))
    for row in result.value['toy']:
        assert row['successes'] == sum(t['found'] for t in row['trials'])
        for trial in row['trials']:
            assert 1 <= trial['attempts'] <= 300
            assert trial['seconds'] >= trial['hash_seconds'] >= 0
            if trial['found']:
                witness = trial['witness']
                assert digest_prefix(bytes.fromhex(witness['left_digest_hex']),row['retained_bits']) == digest_prefix(bytes.fromhex(witness['right_digest_hex']),row['retained_bits'])
                if row['property'] != 'Preimage':
                    assert witness['left_message_hex'] != witness['right_message_hex']
            else:
                assert trial['attempts'] == 300 and trial['witness'] is None


def test_twenty_full_sha256_targets_and_bounded_trial_averages():
    result = hashing_resistance_analysis(attempts=20, repeats=1, sample_count=20).value
    assert len(result['sample_hashes']) == 20
    assert len({row['value_hex'] for row in result['sample_hashes']}) == 20
    assert all(hashlib.sha256(bytes.fromhex(row['value_hex'])).hexdigest() == row['sha256']
               for row in result['sample_hashes'])
    assert result['sample_hash_collisions'] == sum(a['sha256'] == b['sha256']
        for i,a in enumerate(result['sample_hashes']) for b in result['sample_hashes'][i+1:])
    assert len(result['sample_trials']) == 60
    for summary in result['sample_summary']:
        trials = [row for row in result['sample_trials'] if row['property'] == summary['property']]
        assert len(trials) == summary['samples'] == 20
        assert summary['matches'] == sum(row['found'] for row in trials)
        assert summary['mean_attempts_used'] == sum(row['attempts'] for row in trials)/20
        assert all(1 <= row['attempts'] <= 20 for row in trials)
    assert [row['log2_generic_work'] for row in result['theory']] == [256, 256, 128]


def test_prefix_collision_is_actual_distinct_inputs():
    # Pigeonhole principle: 257 distinct inputs must collide in an 8-bit prefix.
    result = _search('Collision',8,257,bytes(32),b'original')
    assert result['found']
    assert result['witness']['left_message_hex'] != result['witness']['right_message_hex']


@pytest.mark.parametrize('operation,args', [
    (confusion_diffusion,(b'short',)),
    (aes_length_analysis,([0],)),
    (aes_length_analysis,([21*1024*1024],)),
    (hashing_resistance_analysis,(b'a',50001)),
    (hashing_resistance_analysis,(b'a',0)),
])
def test_analysis_limits(operation,args):
    with pytest.raises(OperationError) as exc:
        operation(*args)
    assert exc.value.seconds >= 0
