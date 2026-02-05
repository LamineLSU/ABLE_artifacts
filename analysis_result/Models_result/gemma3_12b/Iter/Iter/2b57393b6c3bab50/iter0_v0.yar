rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } //PUSH + POP + MOV + CALL + TEST
        $pattern1 = { 8D 8D 70 ?? ?? ?? ?? E8 48 C2 FE FF } //LEA + CALL
        $pattern2 = { 57 50 50 FF 15 0C 94 39 00 } //PUSH + PUSH + CALL

    condition:
        any of them
}