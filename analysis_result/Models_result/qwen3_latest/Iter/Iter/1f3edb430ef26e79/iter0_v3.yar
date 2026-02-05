rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 52 8B 45 ?? 8B 4D ?? }  ; CALL + PUSH + MOVs (VM check setup)
        $pattern1 = { E8 ?? ?? ?? ?? 52 8B 4D ?? 8B 55 ?? }  ; CALL + PUSH + MOVs (exit trigger setup)
        $pattern2 = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 45 ?? }  ; CALL + TEST + JZ (allocation check)

    condition:
        any of them
}