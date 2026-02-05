rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? 4D CB ?? 9C 7B ?? 3A 63 ?? } 
        $pattern1 = { E8 CE ?? FF FE FE ?? CA ?? FE FE ?? }
        $pattern2 = { 45 F8 8E 71 92 ?? C0 ?? 5D 3A 9C ?? }

    condition:
        any of them
}