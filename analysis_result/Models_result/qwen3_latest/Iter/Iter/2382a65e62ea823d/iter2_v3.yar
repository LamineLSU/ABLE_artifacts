rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 B9 36 DF 35 55 }  // Test instruction with specific displacement
        $pattern1 = { 50 E8 74 0A 00 00 }  // Call to 0041EAE7h with preceding push
        $pattern2 = { 56 56 3D 00 10 00 00 }  // Consecutive PUSH esi and CMP eax, 0x100000

    condition:
        any of them
}