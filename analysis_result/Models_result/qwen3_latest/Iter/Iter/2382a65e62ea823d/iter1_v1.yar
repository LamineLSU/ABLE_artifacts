rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D0 83 C4 ?? 5E 5D }  ; Call ExitProcess + stack cleanup
        $pattern1 = { E8 ?? ?? ?? ?? 8B 06 83 C4 ?? }  ; Call + deref EAX + stack adjust
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  ; Test EAX + conditional jump + mov

    condition:
        any of them
}