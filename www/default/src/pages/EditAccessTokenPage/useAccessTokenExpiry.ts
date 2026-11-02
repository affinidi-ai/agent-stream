import { useState } from 'react';
import {
  newAccessTokenExpiry,
  validateAccessTokenExpiry,
  type AccessTokenExpiryForm,
} from './accessTokenExpiry';

export function useAccessTokenExpiry(initial?: AccessTokenExpiryForm) {
  const [referenceNow] = useState(() => new Date());
  const [form, setForm] = useState(() => initial ?? newAccessTokenExpiry(referenceNow));

  return {
    form,
    setForm,
    referenceNow,
    validate: () => validateAccessTokenExpiry(form.neverExpires, form.expiresAt),
  };
}
