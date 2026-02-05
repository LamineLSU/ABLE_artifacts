rule Bypass_Sample_Evolved
{
    meta:
        description = "Target function check bypass - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 85 C0 74 12 6A 5B 5A 8B CE E3 2F 75 00 00 }
        $pattern2 = { E8 25 05 00 00 8B 45 FC 0F 84 FF FF FF FF }

    condition:
        any of them
}