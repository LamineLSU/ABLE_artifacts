rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific addresses and displacements"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }  // Targets an offset address
        $pattern1 = { 74 ?? ?? ?? }  // Jumps near with displacement
        $pattern2 = { E8 ?? ?? ?? ?? }  // Jumps to absolute address [0x1C8]

    condition:
        any of them
}