rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instruction sequences targeting evasive points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 14 ED DD EB 14 }
        $pattern1 = { 8B 4D 0C EC DD EB 0C }
        $pattern2 = { 8B 88 C4 09 00 00 EC DD EA 00 00 09 C4 }

    condition:
        any of them
}