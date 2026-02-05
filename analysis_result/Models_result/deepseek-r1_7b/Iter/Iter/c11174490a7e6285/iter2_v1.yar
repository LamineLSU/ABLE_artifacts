rule Bypass_Sample
{
    meta:
        description = "Evasion bypass by creating fake function calls in memory"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // Tests EAX and JZ before a call
        $pattern1 = { FF 08 3C 92 00 8B EC 0E 73 DD 53 5D ?? 0F 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? } // Skips a jump near a call
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Skips an instruction after a conditional jump

    condition:
        any of them
}