rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // Test EAX + JE + PUSH
        $pattern1 = { 85 C0 8B CE E8 ?? ?? ?? ?? }  // Test EAX + MOV + CALL (offset wildcard)
        $pattern2 = { B9 42 8C 35 01 50 E8 ?? ?? ?? ?? }  // MOV ECX + PUSH + CALL (offset wildcard)

    condition:
        any of them
}