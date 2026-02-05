rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } //PUSH + POP + MOV + CALL + TEST
        $pattern1 = { 83 BD 60 F9 FF FF 01 6A ?? 5A } //CMP + PUSH + POP
        $pattern2 = { 8B 85 ?? ?? ?? 5E 5F 5B C9 } //MOV + POP + POP + POP + Leave

    condition:
        any of them
}