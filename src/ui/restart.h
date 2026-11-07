// ============================================================================
// restart.h - batch24 P1-4: the save->restart chain.
//
// A config save that needs a restart relaunches the process. The single-
// instance gate is a named kernel event the CURRENT process holds as Primary;
// the replacement only becomes Primary if the event does not exist when it
// claims it. The chain order is therefore load-bearing:
//
//   1. release the gate  (close our handle; the child's CreateEventW then
//                         sees "does not exist" and becomes Primary)
//   2. spawn the child   (same exe + the ORIGINAL command line)
//   3. exit this process (the child owns the process lifetime now)
//
// Releasing AFTER spawning would make the child open the still-held event,
// self-exit as Secondary, and leave NO running instance. Factoring the order
// here keeps it unit-testable without a real process spawn.
// ============================================================================
#pragma once

namespace vgww {
    namespace ui {

        /// Runs the restart chain in the only safe order. `release_gate` drops
        /// the single-instance event, `spawn_child` launches the replacement,
        /// `exit_process` ends this instance. Returns after step 3.
        template <typename ReleaseFn, typename SpawnFn, typename ExitFn>
        void RunRestartChain(ReleaseFn release_gate, SpawnFn spawn_child,
                             ExitFn exit_process) {
            release_gate();  // 1. the child must be able to claim the gate
            spawn_child();   // 2. replacement process (original command line)
            exit_process();  // 3. leave; the child owns the lifetime now
        }

    }  // namespace ui
}  // namespace vgww
