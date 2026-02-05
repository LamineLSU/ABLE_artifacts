rule Bypass_Sample
{
    meta:
        description = "Evasion pattern detection based on function prologue and indirect call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push [ebp+08h], Call to ExitProcess (displacement masked)
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }      // Push [ebp+08h], Call to CRT Exit (displacement masked)
        $pattern2 = { 55 8B EC FF 75 08 }            // Function prologue (push ebp, mov ebp, push [ebp+08h])

    condition:
        any of them
}