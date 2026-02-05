rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with multiple attack vectors"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 9A 6C 70 85 C0 EA EA 9A 6C 72 74 12 E0 9A 5E 83 9A 6C 74 6A 5B 00 00 00 5B }
        $pattern1 = { 9A 61 7A 03 C1 AD EA 00 00 00 5B }
        $pattern2 = { 9A 61 E3 8B 4D EC EB 04 }

    condition:
        any of them
}