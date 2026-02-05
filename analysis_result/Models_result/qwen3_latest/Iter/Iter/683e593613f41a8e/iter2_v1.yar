rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // TEST EAX, EAX + JE + PUSH 0x5B
        $pattern1 = { 74 12 6A 5B 5A 8B CE }  // JE + PUSH 0x5B + POP EDX + MOV ECX, ESI
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE }  // TEST EAX, EAX + JE (wildcard offset) + MOV ECX, ESI

    condition:
        any of them
}