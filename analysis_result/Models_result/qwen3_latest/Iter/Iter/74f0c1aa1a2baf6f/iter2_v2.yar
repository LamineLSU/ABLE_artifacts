rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 8B C8 8A 01 3C 22 75 ?? } // Call + test quote check
        $pattern1 = { 83 65 ?? ?? 8D 45 ?? 50 FF 15 ?? ?? ?? ?? } // Exit decision flow
        $pattern2 = { 3C 20 7F ?? EB ?? 3C 20 7F ?? 41 8A 01 } // Space detection logic

    condition:
        any of them
}