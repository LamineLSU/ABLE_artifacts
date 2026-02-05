rule CorruptedExitCheck
{
    meta:
        description = "Detects potential corrupted exit handling in a PE file"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-05"

    strings:
        $a = { E8 } { 4 bytes } { 59 } { FF 75 08 }  // Call to ___crtCorExitProcess followed by pop ecx and push ebp+08h
        $b = { FF 75 08 } { E8 } { 4 bytes }        // Push ebp+08h followed by call to ___crtCorExitProcess
        $c = { E8 } { 4 bytes } { 59 } { FF 75 08 } // Call to ___crtCorExitProcess followed by pop ecx and push ebp+08h (redundant but valid)

    condition:
        all of them
}