rule EvasionCheck
{
    meta:
        description = "Detects potential evasion logic setup"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { FF 75 08 E8 C1 FF FF FF }  // Push [ebp+08h] followed by call to ___crtCorExitProcess
        $b = { FF 75 03 FF 15 5C C2 4C 00 }  // Push [ebp+03h] followed by call to ExitProcess
        $c = { 55 8B EC FF 75 08 }  // Push ebp, mov ebp, push [ebp+08h]

    condition:
        any of them
}