import React from 'react';
import {FaceFailureReason, SnapKycFaceScanner} from './SnapKycFaceScanner';

/**
 * Face verification step of the share flows (Share tab -> select credential -> share with
 * liveness, plus OpenID4VP and QR login): the BioChq face SDK's liveness check, then its face
 * match against the credential portrait.
 */
export const FaceScanner: React.FC<FaceScannerProps> = props => (
  <SnapKycFaceScanner
    vcImages={props.vcImages}
    onValid={props.onValid}
    onInvalid={props.onInvalid}
    onCancel={props.onCancel}
  />
);

interface FaceScannerProps {
  vcImages: string[];
  onValid: () => void;
  onInvalid: (reason?: FaceFailureReason) => void;
  onCancel: () => void;
}
