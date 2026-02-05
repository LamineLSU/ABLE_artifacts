rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 0C 36 F7 D1 01 F1 21 D1 8D 4C 24 18 } //Leads to a complex calculation, bypassing a potential integrity check
        $pattern1 = { 6A 05 6A 00 50 68 50 80 7C 00 51 6A 00 } //Pushing values onto stack and calling a function. Bypassing a check related to API calls.
        $pattern2 = { 85 C0 74 06 E8 61 2E 1C 04 } //Conditional jump, skipping a check.

    condition:
        any of them
}