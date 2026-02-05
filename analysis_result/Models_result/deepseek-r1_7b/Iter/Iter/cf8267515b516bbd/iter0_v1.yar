rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // Skipping XOR ESP,04h and POP EAX
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Skipping add esp,14h after the call
        $pattern2 = { 0F C0 3C ?? 77 5E 4D 91 4A ?? ?? ?? ?? F5 DD 55 } // Bypassing multiple preceding instructions

    condition:
        any of them
}