rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved specific to exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF C6 5A 8B 4F FC }
        $pattern1 = { 74 12 5A 8D 43 01 85 C0 E8 4B 17 00 00 5F }
        $pattern2 = { 53 8B E5 00 97 6C E0 C3 }

    condition:
        any of them
}