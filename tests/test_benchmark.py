import math
from benchmark_service import run_benchmarks, SIZES


def test_benchmark_actual_results():
    result = run_benchmarks([0, 1024, 10*1024], 3)
    assert result['total_seconds'] >= result['key_generation_seconds'] >= 0
    assert len(result['rows']) == 3
    for row in result['rows']:
        assert row['repeats'] == 3
        for key, value in row.items():
            assert math.isfinite(value) and value >= 0
    assert SIZES[-1] == 10*1024*1024
