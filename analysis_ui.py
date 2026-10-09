"""Graphical analysis workspace; all experimental plots require a real measured run."""
import time
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from analysis_service import confusion_diffusion, aes_length_analysis, hashing_resistance_analysis

COLORS = ['#38bdf8','#6ee7b7','#c4b5fd']


def _figure(title, xlabel, ylabel):
    fig, ax = plt.subplots(figsize=(7,3.7))
    fig.patch.set_facecolor('#121d2d')
    ax.set_facecolor('#121d2d')
    ax.set(title=title, xlabel=xlabel, ylabel=ylabel)
    ax.grid(alpha=.15)
    return fig, ax


def _show(fig):
    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)


def _run(button, state_key, operation, args, failure):
    if st.button(button, type='primary', key=state_key+'_button'):
        start = time.perf_counter()
        try:
            with st.spinner('Running measured experiments…'):
                st.session_state[state_key] = operation(*args)
        except Exception as exc:
            st.session_state.pop(state_key, None)
            failure(exc, start)
    return st.session_state.get(state_key)


def render_analysis(duration, failure):
    st.caption('Controlled experiments · Real measurements · Short explanations')
    avalanche, lengths, hashes = st.tabs(['Confusion & diffusion','Plaintext & key length','Hash resistance'])
    with plt.style.context('dark_background'):
        with avalanche:
            st.caption('Isolated AES-256 block analysis. File encryption and transfer always use AES-256-GCM.')
            inputs = st.columns([2,1])
            block_hex = inputs[0].text_input('16-byte plaintext block (hex)', '00112233445566778899aabbccddeeff', key='analysis_block')
            samples = inputs[1].slider('Bit positions per experiment', 2, 128, 32, key='analysis_samples')
            if st.button('Run confusion & diffusion', type='primary'):
                start = time.perf_counter()
                try:
                    st.session_state.analysis_avalanche = confusion_diffusion(bytes.fromhex(block_hex), samples)
                except Exception as exc:
                    st.session_state.pop('analysis_avalanche', None)
                    failure(exc, start)
            result = st.session_state.get('analysis_avalanche')
            if not result:
                st.info('Run the experiment to compare single-bit plaintext and key changes.')
            else:
                duration('Complete confusion / diffusion experiment', result.seconds)
                duration('Random AES key setup', result.value['key_setup_seconds'])
                duration('Baseline AES block encryption', result.value['baseline_encryption_seconds'])
                df = pd.DataFrame(result.value['rows'])
                columns = st.columns(2)
                for column, kind, title, color in zip(columns,
                    ['Plaintext bit flip','Key bit flip'], ['Diffusion · change one plaintext bit','Confusion illustration · change one key bit'], COLORS):
                    with column:
                        subset = df[df.experiment == kind]
                        st.metric('Mean changed output bits', f'{subset.changed_percent.mean():.2f}%')
                        fig, ax = _figure(title, 'Flipped input bit position (LSB first in each byte)', 'Ciphertext bits changed (%)')
                        ax.plot(subset.flipped_bit, subset.changed_percent, marker='o', markersize=3, color=color, label='Measured AES output change')
                        ax.axhline(50, color='#8ca1bc', ls='--', label='50% reference')
                        ax.set_ylim(0,100); ax.legend(fontsize=8)
                        _show(fig)
                        st.caption('One plaintext bit changes many output bits: diffusion spreads input changes.' if kind == 'Plaintext bit flip' else 'One key bit changes many output bits: this illustrates key sensitivity, not a formal proof of confusion.')
                        mask = result.value['first_trial_masks'][kind]
                        fig, ax = _figure('First trial · changed ciphertext bits', 'Bit column', 'Row of 16 consecutive bits')
                        ax.imshow([mask[i:i+16] for i in range(0,128,16)], cmap='Blues', vmin=0,vmax=1, aspect='auto')
                        ax.grid(False)
                        _show(fig)
                        st.caption('Bright = changed; dark = unchanged. The first trial flips bit 0. Each trial changes exactly one bit.')
                st.caption('Samples use evenly spaced positions in the 128-bit plaintext and 256-bit key. The same key/block baseline is used throughout. Single-block ECB is isolated here; no file uses ECB and no GCM nonce is reused. Results need not equal 50% and do not prove security.')
                with st.expander('Measured trial timings & ciphertext baseline'):
                    st.code(result.value['baseline_hex'], language=None)
                    st.dataframe(df, hide_index=True, width='stretch')
                st.download_button('Download confusion / diffusion CSV', df.to_csv(index=False), 'confusion-diffusion.csv', 'text/csv')

        with lengths:
            st.caption('Compare AES-GCM with 128-, 192- and 256-bit keys. These experimental key sizes never change file-vault or transfer settings.')
            result = _run('Run plaintext & key length benchmark', 'analysis_lengths', aes_length_analysis, (), failure)
            if not result:
                st.info('Run the benchmark to measure all six plaintext sizes and all three AES key sizes.')
            else:
                duration('Total length-analysis benchmark', result.seconds)
                df = pd.DataFrame(result.value['rows'])
                columns = st.columns(2)
                for column, field, title in zip(columns, ['encrypt_ms','decrypt_ms'], ['Encryption vs plaintext length','Decryption vs plaintext length']):
                    with column:
                        fig, ax = _figure(title, 'Plaintext size (KiB, logarithmic scale)', 'Median duration (ms)')
                        for bits,color in zip((128,192,256),COLORS):
                            subset = df[df.key_bits == bits]
                            ax.plot(subset.size_KiB,subset[field],marker='o',color=color,label=f'AES-{bits}-GCM')
                        ax.set_xscale('log'); ax.legend(fontsize=8)
                        _show(fig)
                        st.caption('Longer plaintext means more bytes to process. Small inputs are dominated by call overhead; acceleration and timing noise affect the curve.')
                sizes = sorted(df.size_bytes.unique().tolist())
                selected = st.selectbox('Hold plaintext size fixed for key-length comparison', sizes,
                                        index=min(3,len(sizes)-1), format_func=lambda n:f'{n/1024:g} KiB')
                subset = df[df.size_bytes == selected]
                fig, ax = _figure(f'Key length comparison · {selected/1024:g} KiB plaintext', 'AES key length (bits)', 'Median duration (ms)')
                for field,color,title in zip(['encrypt_ms','decrypt_ms'],COLORS,['Encryption','Decryption']):
                    ax.plot(subset.key_bits,subset[field],marker='o',color=color,label=title)
                ax.set_xticks([128,192,256]); ax.legend()
                _show(fig)
                st.caption('The plaintext is identical for each key size. AES-128/192/256 uses 10/12/14 rounds; measured runtime may not rise monotonically because of hardware acceleration and noise. Key size is in bits; password length is a different quantity.')
                with st.expander('Measurements & setup timings'):
                    st.dataframe(df,hide_index=True,width='stretch')
                st.caption('Median of 3 trials. Every trial uses a new key and nonce and checks recovered bytes. Curves exclude key generation/setup, random-data generation and password derivation; setup is timed in the table. Throughput is bytes / 1,000,000 / seconds.')
                st.download_button('Download length-analysis CSV',df.to_csv(index=False),'aes-length-analysis.csv','text/csv')

        with hashes:
            controls = st.columns([2,1])
            message = controls[0].text_input('Original message for second-preimage analysis', 'CipherVault hash analysis', max_chars=1024)
            attempts = controls[1].select_slider('Search budget per trial', options=[1000,5000,10000,20000,50000], value=20000)
            st.caption('Full SHA-256 searches are bounded. Separate 8/12/16-bit prefix experiments make search behavior visible; prefix matches are not SHA-256 breaks.')
            result = _run('Run hash resistance analysis','analysis_hashes',hashing_resistance_analysis,(message.encode(),attempts),failure)
            if not result:
                st.info('Run the experiment for preimage, second-preimage and collision graphs.')
            else:
                duration('Total hash-resistance analysis',result.seconds)
                duration('SHA-256 target preparation',result.value['target_hash_seconds'])
                full = result.value['full']
                toy = pd.DataFrame([{k:v for k,v in row.items() if k != 'trials'} for row in result.value['toy']])
                summaries = st.columns(3)
                explanations = {
                    'Preimage':'Given a digest, find any input producing it. Retaining more digest bits generally increases search work.',
                    'Second preimage':'Given an original message, find a different message with the same digest. The original itself is never a candidate match.',
                    'Collision':'Find any two different messages with the same digest. Birthday search usually finds prefix collisions with fewer trials than a fixed-target search.'}
                for summary,experiment in zip(summaries,full):
                    summary.metric(experiment['property']+' · full SHA-256 matches',int(experiment['found']))
                for experiment in full:
                    kind = experiment['property']
                    st.subheader(kind+' resistance')
                    graphs = st.columns(2)
                    with graphs[0]:
                        trace = pd.DataFrame(experiment['progress'])
                        fig,ax = _figure('Full SHA-256 · bounded search','Candidate hashes evaluated','Matching digests found')
                        ax.step(trace.attempts,trace.matches,where='post',color=COLORS[0],label=kind)
                        ax.set_ylim(-.05,1.1);ax.set_yticks([0,1]);ax.legend()
                        _show(fig)
                    with graphs[1]:
                        subset = toy[toy.property == kind]
                        fig,ax = _figure('Toy SHA-256 prefixes · actual searches','Retained digest bits','Median attempts used (log scale)')
                        ax.bar(subset.retained_bits,subset.median_attempts_used,width=2,color=COLORS[1])
                        ax.set_yscale('log');ax.set_xticks([8,12,16])
                        for row in subset.itertuples():
                            ax.annotate(f'{row.successes}/{row.repeats} found',(row.retained_bits,row.median_attempts_used),xytext=(0,5),textcoords='offset points',ha='center',fontsize=9)
                        ax.margins(y=.25)
                        _show(fig)
                    st.caption(explanations[kind]+f' Full digest: {int(experiment["found"])} match in {experiment["attempts"]:,} attempts. Toy bars include exhausted budgets; a capped trial is a failure, not a found match.')
                    duration(kind+' search (includes hashing and lookup)',experiment['seconds'])
                    duration(kind+' SHA-256 computations',experiment['hash_seconds'])
                fig,ax = _figure('Theoretical generic classical search work · not measured','Resistance property','log₂(work), approximate hash evaluations')
                theory = result.value['theory']
                bars = ax.bar([row['property'] for row in theory],[row['log2_generic_work'] for row in theory],color=COLORS)
                for bar,row in zip(bars,theory):
                    ax.text(bar.get_x()+bar.get_width()/2,bar.get_height()+3,f'≈ 2^{row["log2_generic_work"]}',ha='center',fontsize=10)
                ax.set_ylim(0,285)
                _show(fig)
                st.caption('Ideal generic estimates for full SHA-256 and ordinary short messages: roughly 2²⁵⁶ work for preimage/second preimage and 2¹²⁸ for collisions. This is theory, not measured time. Message structure/length can affect second-preimage security. Small searches and avalanche measurements do not prove resistance.')
                with st.expander('Hash measurements, failed searches & prefix-match examples'):
                    st.code(result.value['original_sha256'],language=None)
                    st.dataframe(toy,hide_index=True,width='stretch')
                    examples = [trial['witness'] for row in result.value['toy'] for trial in row['trials'] if trial['found']]
                    st.json(examples[:3])
                    st.caption('Examples show full digests whose retained prefixes match. The full 256-bit digests can still differ. Median hashing and complete search timings are separate table columns.')
                st.download_button('Download hash-resistance CSV',toy.to_csv(index=False),'hash-resistance-analysis.csv','text/csv')
        with st.expander('Analysis references'):
            st.markdown('[NIST AES specification](https://csrc.nist.gov/pubs/fips/197/final) · [NIST hash properties](https://csrc.nist.gov/projects/hash-functions) · [NIST generic hash strength estimates](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf)')
