rule ExitCheck_Logic
{
    meta:
        description = "Detects evasion logic via exit check patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Researcher"
    
    strings:
        $a = { FF 75 08 E8 C8 FF FF FF } // Push [ebp+08h] + call ___crtCorExitProcess
        $b = { FF 75 08 FF 15 AC B0 41 00 } // Push [ebp+08h] + call ExitProcess
        $c = { 55 8B EC FF 75 08 } // Push ebp + mov ebp, esp + push [ebp+08h]
    
    condition:
        any of ($a, $b, $c)
}