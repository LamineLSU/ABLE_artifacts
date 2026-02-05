rule EvasionCheck
{
    meta:
        description = "Detects evasion checks before termination"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { E8 ?? ?? ?? ?? } {83F801} {74??}  // call + cmp + je
        $b = { FF 15 3C F1 42 00 } {50} {FF1540F14200}  // GetCurrentProcess + push + TerminateProcess
        $c = { C1 E8 08 } {A801} {7510}  // shr + test al + jne
    condition:
        any of ($a, $b, $c)
}