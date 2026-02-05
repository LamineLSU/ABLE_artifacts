rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + JE (check logic)
        $pattern1 = { FF 15 88 A0 B8 00 }           // Specific call to 00B8A088h
        $pattern2 = { FF 15 2C A1 B8 00 }           // Specific call to 00B8A12Ch

    condition:
        any of them
}