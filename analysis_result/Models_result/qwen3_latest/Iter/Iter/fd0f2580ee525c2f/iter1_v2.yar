rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX, JE (evasion check)
        $pattern1 = { E8 74 FA FF FF 85 C0 }      // Call + Test EAX (setup for evasion)
        $pattern2 = { 33 DB BA 21 05 00 00 }      // XOR EBX, MOV EDX (register nullification)

    condition:
        any of them
}