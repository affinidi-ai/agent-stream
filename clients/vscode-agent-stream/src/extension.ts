import * as vscode from 'vscode';

import { acquireToken } from './auth';
import { initLog, log, logError, showLog } from './log';
import { createProvider, resolveSignInConfig } from './provider';

export function activate(context: vscode.ExtensionContext): void {
  initLog(context);
  log('Agent Stream extension activated.');

  const didChangeModels = new vscode.EventEmitter<void>();
  context.subscriptions.push(didChangeModels);

  context.subscriptions.push(
    vscode.lm.registerLanguageModelChatProvider(
      'agent-stream',
      createProvider(didChangeModels.event),
    ),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (
        event.affectsConfiguration('agentStream.models') ||
        event.affectsConfiguration('agentStream.endpoint') ||
        event.affectsConfiguration('agentStream.modelsPath') ||
        event.affectsConfiguration('agentStream.chatPath') ||
        event.affectsConfiguration('agentStream.allowLocalEndpoints')
      ) {
        log('Configuration changed; refreshing model list.');
        didChangeModels.fire();
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('agent-stream.signIn', async () => {
      log('Sign-in requested.');
      try {
        const session = await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: 'Agent Stream: signing in with Microsoft Entra ID…',
          },
          async () => {
            // Pull the surface's public bootstrap (central tenant/client/scopes)
            // first, exactly like model discovery, so the command signs in from
            // the Access Point URL alone instead of only the manual settings.
            const entra = await resolveSignInConfig();
            return acquireToken(true, entra);
          },
        );
        if (session) {
          didChangeModels.fire();
          log(`Signed in as ${session.account.label}.`);
          void vscode.window.showInformationMessage(
            `Agent Stream: signed in as ${session.account.label}.`,
          );
        } else {
          log('Sign-in returned no session.');
          void vscode.window
            .showWarningMessage(
              'Agent Stream: sign-in did not return a session.',
              'Show Logs',
            )
            .then((choice) => {
              if (choice === 'Show Logs') {
                showLog();
              }
            });
        }
      } catch (error) {
        logError('Sign-in failed', error);
        void vscode.window
          .showErrorMessage(
            `Agent Stream: ${error instanceof Error ? error.message : String(error)}`,
            'Show Logs',
          )
          .then((choice) => {
            if (choice === 'Show Logs') {
              showLog();
            }
          });
      }
    }),
    vscode.commands.registerCommand('agent-stream.signOut', async () => {
      void vscode.window.showInformationMessage(
        'Agent Stream uses your Microsoft account. Sign out from the Accounts menu (bottom-left) to revoke access.',
      );
    }),
    vscode.commands.registerCommand('agent-stream.showLogs', () => {
      showLog();
    }),
    vscode.commands.registerCommand('agent-stream.refreshModels', () => {
      log('Manual model refresh requested.');
      didChangeModels.fire();
      void vscode.window.showInformationMessage('Agent Stream: refreshing models from the IDE Surface.');
    }),
  );
}

export function deactivate(): void {
  // Nothing to clean up; disposables are managed by the extension context.
}
