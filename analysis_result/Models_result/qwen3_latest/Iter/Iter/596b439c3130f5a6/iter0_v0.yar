rule MaliciousBehavior_Detector
{
    meta:
        description = "Detects suspicious system calls and low-level operations associated with malicious behavior"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2025-03-15"
        license = "BSD (3-clause)"

    strings:
        $a = { 8B 06 83 C4 14 52 FF D0 } // Call to ExitProcess with stack manipulation
        $b = { 8B 16 50 51 FF D2 }        // Call to RtlAllocateHeap
        $c = { 8B EC 51 8B 16 50 51 52 E6 85 C0 } // in al, dx with surrounding push and test

    condition:
        all of them
}