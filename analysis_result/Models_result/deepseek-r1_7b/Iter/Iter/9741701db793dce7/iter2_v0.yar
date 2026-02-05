rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - tailored to specific code exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85C0 E8E0A2FFFF }
        $pattern1 = { 85C0 E8431C0000 }
        $pattern2 = { 6A00 E8431C0000 }
}

pattern0: bytes
 85 C0 E8 E0 A2 FFFF

pattern1: bytes
 85 C0 8B 45 FC 55 ??

pattern2: bytes
 6A00 8B 45 FC 55 ??