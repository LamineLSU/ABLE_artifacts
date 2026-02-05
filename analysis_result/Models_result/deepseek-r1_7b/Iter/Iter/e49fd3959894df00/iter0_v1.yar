rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detected via conditional jumps and test skips"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 43 56 33 DB 56 57 8B B5 FF 15 44 74 }
        $pattern1 = { 19 22 53 56 57 FF 0F 8B F8 FF 15 47 4C }
        $pattern2 = { 16 19 E8 82 3D 01 00 41 F8 50 }
    condition:
        any of them
}