// Each style from its own folder: the package root requires all 18 styles, so all 18 font files
// would be bundled.
import {useFonts} from 'expo-font';
import {Montserrat_200ExtraLight} from '@expo-google-fonts/montserrat/200ExtraLight';
import {Montserrat_400Regular} from '@expo-google-fonts/montserrat/400Regular';
import {Montserrat_500Medium} from '@expo-google-fonts/montserrat/500Medium';
import {Montserrat_600SemiBold} from '@expo-google-fonts/montserrat/600SemiBold';
import {Montserrat_700Bold} from '@expo-google-fonts/montserrat/700Bold';

export function useFont() {
  const [hasFontsLoaded] = useFonts({
    Montserrat_400Regular,
    Montserrat_500Medium,
    Montserrat_600SemiBold,
    Montserrat_700Bold,
    Montserrat_200ExtraLight,
  });

  return hasFontsLoaded;
}
