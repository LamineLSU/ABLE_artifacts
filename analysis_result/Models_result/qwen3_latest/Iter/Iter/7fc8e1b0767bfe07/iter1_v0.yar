rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // TEST EAX + JE + PUSH 0x5B
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }  // TEST EAX + JE with offset
        $pattern2 = { 6A 40 53 8B 4D F8 }  // PUSH 0x40 + PUSH EBX + MOV ECX

    condition:
        any of them
}