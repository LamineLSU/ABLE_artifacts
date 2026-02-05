rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? }
        // Skips TEST EAX and JZ
        $pattern1 = { 74 ?? 0B FF ?? ?? ?? ?? ?? }
        // Skips conditional jump (near/jump)
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? ?? }
        // Wildcarded displacement in a call
    condition:
        any of them
}