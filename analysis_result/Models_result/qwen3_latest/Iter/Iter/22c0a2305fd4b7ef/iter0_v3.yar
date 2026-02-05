rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 07 50 FF 15 ?? ?? ?? ?? }  // Test EAX, JE, Push EAX, Call [Address]
        $pattern1 = { 33 C9 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? }  // XOR ECX, CALL, MOV EAX [Address]
        $pattern2 = { 03 C1 B9 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? }  // ADD EAX, ECX, MOV ECX [Address], PUSH, CALL

    condition:
        any of them
}