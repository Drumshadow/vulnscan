# Tune-set ablation (dev_nc, sample tune), paired vs harness v1

## harness_v2:dev_nc:089bd80b2f
242 items done of sample 'tune'; baseline harness_inv:dev_nc:af0d92409c

| combination | pair acc | recall | precision | benign flagged | fix-site flagged | Δ pair acc vs baseline (95% CI) |
|---|---|---|---|---|---|---|
| baseline | 17% | 26% | 25% | 24% | 12% | - |
| main1 | 18% | 21% | 20% | 28% | 9% | +1.0% (-6.4%..+9.2%), n=96 pairs |
| vote2 | 0% | 0% | n/a | 0% | 0% | -16.7% (-24.5%..-9.8%), n=96 pairs |
| union1 | 18% | 21% | 20% | 28% | 9% | +1.0% (-6.4%..+9.2%), n=96 pairs |

## harness_v2:dev_nc:2c3359a1ad
242 items done of sample 'tune'; baseline harness_inv:dev_nc:af0d92409c

| combination | pair acc | recall | precision | benign flagged | fix-site flagged | Δ pair acc vs baseline (95% CI) |
|---|---|---|---|---|---|---|
| baseline | 17% | 26% | 25% | 24% | 12% | - |
| main1 | 16% | 18% | 18% | 24% | 10% | -1.0% (-9.9%..+7.7%), n=96 pairs |
| vote2 | 14% | 17% | 25% | 18% | 6% | -3.1% (-10.3%..+4.2%), n=96 pairs |
| union3 | 23% | 29% | 20% | 42% | 18% | +6.2% (-2.2%..+14.9%), n=96 pairs |
| main1+lenses | 15% | 20% | 13% | 44% | 24% | -2.1% (-10.9%..+7.1%), n=96 pairs |
| vote2+lenses | 11% | 19% | 15% | 36% | 22% | -5.2% (-13.6%..+3.1%), n=96 pairs |
| union3+lenses | 20% | 30% | 17% | 54% | 29% | +3.1% (-6.5%..+13.0%), n=96 pairs |

## harness_v2:dev_nc:2df0471946
242 items done of sample 'tune'; baseline harness_inv:dev_nc:af0d92409c

| combination | pair acc | recall | precision | benign flagged | fix-site flagged | Δ pair acc vs baseline (95% CI) |
|---|---|---|---|---|---|---|
| baseline | 17% | 26% | 25% | 24% | 12% | - |
| main1 | 16% | 23% | 19% | 34% | 12% | -1.0% (-9.7%..+7.2%), n=96 pairs |
| vote2 | 0% | 0% | n/a | 0% | 0% | -16.7% (-24.5%..-9.8%), n=96 pairs |
| union1 | 16% | 23% | 19% | 34% | 12% | -1.0% (-9.7%..+7.2%), n=96 pairs |
| twostep | 17% | 26% | 16% | 56% | 24% | +0.0% (-8.9%..+9.1%), n=96 pairs |
| invariants | 20% | 26% | 22% | 40% | 15% | +3.1% (-5.3%..+11.3%), n=96 pairs |
| main1+twostep | 19% | 30% | 18% | 58% | 25% | +2.1% (-7.3%..+11.6%), n=96 pairs |
| main1+invariants | 19% | 29% | 20% | 46% | 20% | +2.1% (-6.7%..+10.8%), n=96 pairs |
| main1+twostep+invariants | 20% | 33% | 19% | 62% | 27% | +3.1% (-6.3%..+12.4%), n=96 pairs |

## Freeze candidate on the check split: harness_v2:dev_nc:e1eb808703
166 items done of sample 'check'; baseline harness_inv:dev_nc:af0d92409c

| combination | pair acc | recall | precision | benign flagged | fix-site flagged | Δ pair acc vs baseline (95% CI) |
|---|---|---|---|---|---|---|
| baseline | 13% | 18% | 19% | 10% | 16% | - |
| main1 | 12% | 19% | 23% | 10% | 10% | -1.5% (-10.1%..+7.1%), n=68 pairs |
| vote2 | 0% | 0% | n/a | 0% | 0% | -13.2% (-21.1%..-6.0%), n=68 pairs |
| union1 | 12% | 19% | 23% | 10% | 10% | -1.5% (-10.1%..+7.1%), n=68 pairs |
