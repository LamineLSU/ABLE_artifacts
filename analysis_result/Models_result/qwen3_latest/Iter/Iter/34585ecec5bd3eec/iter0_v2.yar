rule ProcessTerminationAndCleanup
{
    meta:
        description = "Identifies the use of ExitProcess and CloseHandle in a malicious context, often seen in process termination or cleanup routines."
        cape_options = "bp0=$call_exitprocess+0,action0=skip,bp1=$call_closehandle+0,action1=skip,bp2=$je_after_test+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"

    strings:
        // Call to ExitProcess (assuming it's at a known offset in the PE)
        $call_exitprocess = { E8 ?? ?? ?? ?? } // E8 is CALL, followed by a 4-byte offset
        // Call to CloseHandle (assuming it's at a known offset in the PE)
        $call_closehandle = { E8 ?? ?? ?? ?? }
        // Conditional jump (je) following a test instruction
        $je_after_test = { 74 ?? }

    condition:
        // Match any of the three patterns
        (all of
            (any of
                (all of
                    $call_exitprocess
                    (import "kernel32" "ExitProcess")
                )
                (all of
                    $call_closehandle
                    (import "kernel32" "CloseHandle")
                )
                (all of
                    $je_after_test
                    (import "kernel32" "ExitProcess")
                )
            )
        )
}