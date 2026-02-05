rule ExitProcessCallPattern
{
    meta:
        description = "Detects a call to ExitProcess or similar functions, possibly indicating program termination."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"
    strings:
        $a = { FF 75 08 E8 C1 FF FF FF }  // push + call to CRT exit function
        $b = { FF 15 5C C2 4C 00 }       // call to ExitProcess
        $c = { 59 FF 75 08 FF 15 5C C2 4C 00 }  // pop + push + call to ExitProcess
    condition:
        all of them
}