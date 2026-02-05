rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 ?? 0C ?? ?? ?? ?? }     // Detects JZ offset 3 in WaitForE041()
        $pattern1 = { E8 ?? ?? ?? ?? ?? }       // Detects E8 with nearby conditional jumps
        $pattern2 = { C3 ?? ?? ?? ?? 6D ?? ?? ?? }     // Detects JZ near function calls

    condition:
        any of them
}