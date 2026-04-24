rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific evasion checks and exit decision"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? }
        $pattern1 = { 00 B5 61 F8 E8 25 05 00 00 BA 21 05 00 00 33 DB ?? ?? ?? ?? 53 ?? } [17-19 bytes]
        $pattern2 = { 03 C3 03 C1 ?? E0 10 8B C7 ?? E0 01 8D 43 01 } [11 bytes]

    condition:
        any of them
}