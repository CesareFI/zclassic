# zstats

Streaming statistics for C23.

- Exact count-weighted mean rounded once to binary64, scaled variance,
  min/max, and a rounded long-double running total.
- `add_repeated` for k identical samples in one step.
- `merge` (Chan's parallel algorithm) for combining partial
  accumulators from workers.
- Appends merge a constant block through the same arithmetic. Negative M2
  in a nonempty destination, count overflow and NULL refuse without mutation;
  repeating zero samples is a no-op. Empty payloads are ignored. A first
  constant block has M2=0; combining nonempty operands with nonfinite means
  makes M2 NaN. The header specifies infinity, NaN and signed-zero policies.
- No allocation, no wall clock, no dependencies beyond libc (`sqrt` is
  an internal Newton iteration, so no libm either).

## API

```c
#include <zstats/zstats.h>

zstats s;
zstats_init(&s);
zstats_add(&s, 2.0);
zstats_add_repeated(&s, 7.5, 100);
zstats_merge(&s, &partial);

zstats_count(&s);
zstats_mean(&s);
zstats_variance(&s);         /* population */
zstats_sample_variance(&s);  /* n-1 */
zstats_stddev(&s);
zstats_min(&s); zstats_max(&s); zstats_total(&s);
```

## CLI

```sh
zstats 2 4 4 4 5 5 7 9
seq 1 100 | zstats
```

## License

Apache-2.0. See LICENSE.
