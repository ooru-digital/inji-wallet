import React, {useState} from 'react';
import {FaceScanner} from '../components/FaceScanner/FaceScanner';
import {
  FaceFailureReason,
  FaceVerificationFailedView,
} from '../components/FaceScanner/SnapKycFaceScanner';
import {Column} from '../components/ui';
import {Theme} from '../components/ui/styleUtils';
import {VerifiableCredential} from '../machines/VerifiableCredential/VCMetaMachine/vc';
import {Modal} from '../components/ui/Modal';

export const VerifyIdentityOverlay: React.FC<
  VerifyIdentityOverlayProps
> = props => {
  const credential = props.credential;
  // Kept here, not in the share machines: this overlay shows both the scanner and the failure
  // page, so it knows why the last check failed.
  const [failureReason, setFailureReason] =
    useState<FaceFailureReason>('notVerified');
  const onFaceInvalid = (reason?: FaceFailureReason) => {
    setFailureReason(reason ?? 'notVerified');
    props.onFaceInvalid();
  };

  // The face verification page draws its own header.
  const modalProps = {
    isVisible: props.isVerifyingIdentity,
    onDismiss: props.onCancel,
    animationType: 'slide',
    arrowLeft: false,
    headerTitle: '',
    presentationStyle: 'overFullScreen',
    showClose: false,
    showHeader: false,
  };

  return (
    <>
      <Modal {...modalProps}>
        <Column
          fill
          style={[
            Theme.VerifyIdentityOverlayStyles.content,
            // A box the size of the whole screen would push the face page's Cancel button
            // under Android's navigation bar; that page lays itself out.
            {height: undefined},
          ]}
          align="center">
          {credential != null && (
            <FaceScanner
              vcImages={props.verifiableCredentialData
                .map(data => data.face)
                .filter(face => face !== undefined)}
              onValid={props.onFaceValid}
              onInvalid={onFaceInvalid}
              onCancel={props.onCancel}
            />
          )}
        </Column>
      </Modal>

      <FaceVerificationFailedView
        isVisible={props.isInvalidIdentity}
        reason={failureReason}
        onRetry={props.onRetryVerification}
        onCancel={props.onNavigateHome}
      />
    </>
  );
};

export interface VerifyIdentityOverlayProps {
  credential?: [VerifiableCredential | Credential];
  verifiableCredentialData: any;
  isVerifyingIdentity: boolean;
  onCancel: () => void;
  onFaceValid: () => void;
  onFaceInvalid: () => void;
  isInvalidIdentity: boolean;
  onNavigateHome: () => void;
  onRetryVerification: () => void;
}
