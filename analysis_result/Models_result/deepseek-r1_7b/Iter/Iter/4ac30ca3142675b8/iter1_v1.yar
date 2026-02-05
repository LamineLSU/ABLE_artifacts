rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 49 5D 74 63 8B 45 FC }
        $pattern1 = { 49 5E BC F5 83 F8 01 74 8B 4D 0C }
        $pattern2 = { 49 5F 4A 64 83 F8 01 74 8B 4D 0C }

    condition:
        (any)
}