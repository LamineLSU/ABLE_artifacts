rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 74 07 }  // Call CloseHandle + Test EAX + JE
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // Call + Test EAX + JZ
        $pattern2 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }  // PUSH + POP + MOV + CALL

    condition:
        any of them
}