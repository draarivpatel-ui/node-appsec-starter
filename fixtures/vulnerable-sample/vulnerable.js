import { exec } from 'node:child_process';

export function runUserCommand(name) {
  exec(`convert ${name}`);
}

export function evaluateUserRule(source) {
  return eval(source);
}

export function renderProfile(element, html) {
  element.innerHTML = html;
}
