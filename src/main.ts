import './styles.css';
import { initState } from './ui/state';
import { mountIntro } from './ui/intro';
import { mountAttack } from './ui/attack';
import { mountLadder } from './ui/ladder';
import { mountStepper } from './ui/stepper';
import { mountVrf } from './ui/vrf';
import { mountMonitor } from './ui/monitor';
import { mountScope } from './ui/scope';

async function boot(): Promise<void> {
  await initState();
  const mount = document.getElementById('exhibits')!;
  mountIntro(mount);
  mountAttack(mount);
  mountLadder(mount);
  mountStepper(mount);
  mountVrf(mount);
  mountMonitor(mount);
  mountScope(mount);
}

void boot();
