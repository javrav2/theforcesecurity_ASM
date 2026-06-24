import Image from 'next/image'
import { cn } from '@/lib/utils'

interface JudahLogoProps {
  className?: string
  size?: number
}

export function JudahLogo({ className, size = 80 }: JudahLogoProps) {
  return (
    <Image
      src="/logo.png"
      alt="Judah Security"
      width={size}
      height={size}
      className={cn('object-contain', className)}
    />
  )
}
