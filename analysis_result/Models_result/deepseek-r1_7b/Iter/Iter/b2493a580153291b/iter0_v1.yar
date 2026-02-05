rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns using FPU and stack canisters"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 EB F8 F4 FA DD E8 17 D0 00 00 CD AF CA }
        $pattern1 = { 55 EB 2F EB EB AC CA E8 17 D0 00 00 AE FC CA }
        $pattern2 = { 55 EB 8B 45 DE E8 17 D0 00 00 CD AB ED }

    condition:
        any of them
}