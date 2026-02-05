rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }  // Test EAX + JE + PUSH + POP + MOV + CALL
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? }    // Test EAX + JZ + CALL (second check)
        $pattern2 = { 8B 85 F0 FE FF FF BA 04 01 00 00 E8 ?? ?? ?? ?? }  // MOV + ADD + CALL (third check)

    condition:
        any of them
}