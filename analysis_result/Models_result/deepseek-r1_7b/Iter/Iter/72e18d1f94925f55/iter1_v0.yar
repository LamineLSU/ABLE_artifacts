rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 16 20 E8 CD 3D 00 00 83 F8 01 74 20 }
        $pattern1 = { 20 FF EE CE E8 BF 31 E7 04 ?? }
        $pattern2 = { 20 FF EE CE E8 95 DB 43 74 ?? }
        
    condition:
        any of them
}