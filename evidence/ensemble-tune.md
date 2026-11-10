# Local ensemble on tune (96 pairs + 50 ordinary commits), paired vs harness v1

| variant | pair acc | recall | ordinary flagged | delta vs v1 (95% CI) |
|---|---|---|---|---|
| nemotron alone | 9% | 16% | 58% | -7.3% (-15.5%..+1.0%) |
| qwen (context fix) alone | 18% | 21% | 28% | +1.0% (-6.4%..+9.2%) |
| union | 16% | 29% | 66% | -1.0% (-9.2%..+7.1%) |
| both agree | 6% | 6% | 10% | -10.4% (-18.1%..-3.1%) |
